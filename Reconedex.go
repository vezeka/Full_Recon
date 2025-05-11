package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func main() {
	// Récupération des arguments : domaine cible et dossier de reprise
	domain := flag.String("domain", "", "Domaine cible")
	targetDir := flag.String("target", "", "Dossier de travail (pour sortie et reprise)")
	flag.Parse()

	if *domain == "" || *targetDir == "" {
		log.Fatal("Usage : -domain <domaine> -target <dossier>")
	}

	// Création des dossiers de sortie
	outputsDir := filepath.Join(*targetDir, "outputs")
	urlsDir := filepath.Join(*targetDir, "urls")
	os.MkdirAll(outputsDir, 0755)
	os.MkdirAll(urlsDir, 0755)

	// Étape 1 : Collecte des sous-domaines
	mergedFile := filepath.Join(outputsDir, "subdomains_merged.txt")
	if _, err := os.Stat(mergedFile); os.IsNotExist(err) {
		log.Println("Étape 1 : Collecte des sous-domaines")
		if err := step1(*domain, outputsDir); err != nil {
			log.Fatalf("Erreur à l'étape 1 : %v", err)
		}
	} else {
		log.Println("Étape 1 déjà complétée, reprise...")
	}

	// Étape 2 : Analyse des codes HTTP sur les sous-domaines
	status200File := filepath.Join(outputsDir, "subdomains_status_200.txt")
	if _, err := os.Stat(status200File); os.IsNotExist(err) {
		log.Println("Étape 2 : Analyse HTTP sur les sous-domaines")
		if err := step2(outputsDir); err != nil {
			log.Fatalf("Erreur à l'étape 2 : %v", err)
		}
	} else {
		log.Println("Étape 2 déjà complétée, reprise...")
	}

	// Étape 3 : Extraction des URLs
	mergedFile = filepath.Join(outputsDir, "subdomains_merged.txt")
	progressFile := filepath.Join(outputsDir, "progress.txt")

	// Read the merged file to get the total number of subdomains
	data, err := ioutil.ReadFile(mergedFile)
	if err != nil {
		log.Fatalf("Erreur lors de la lecture du fichier merged : %v", err)
	}
	lines := strings.Split(string(data), "\n")
	totalSubdomains := len(lines)

	// Read the progress file to get the last processed index
	var lastProcessedIndex int
	if _, err := os.Stat(progressFile); err == nil {
		content, err := ioutil.ReadFile(progressFile)
		if err == nil {
			fmt.Sscanf(string(content), "%d", &lastProcessedIndex)
		}
	}

	// Check if all subdomains have been processed
	if lastProcessedIndex < totalSubdomains {
		log.Println("Étape 3 : Extraction des URLs")
		if err := step3(outputsDir); err != nil {
			log.Fatalf("Erreur à l'étape 3 : %v", err)
		}
	} else {
		log.Println("Étape 3 déjà complétée, reprise...")
	}

	// Étape 4 : Vérification basée sur le fichier et le dossier
	urlsExtractedFile := filepath.Join(outputsDir, "urls_extracted.txt")

	// Vérifier si le fichier urls_extracted.txt existe et n'est pas vide
	shouldRunStep4 := false
	if fileInfo, err := os.Stat(urlsExtractedFile); err == nil && fileInfo.Size() > 0 {
		log.Printf("Le fichier urls_extracted.txt existe et contient %d bytes de données", fileInfo.Size())

		// Vérifier l'état du dossier urls
		dirExists := true
		if _, err := os.Stat(urlsDir); os.IsNotExist(err) {
			dirExists = false
			log.Printf("Le dossier urls n'existe pas encore")
		}

		if !dirExists {
			// Le dossier n'existe pas, on doit exécuter l'étape 4
			shouldRunStep4 = true
		} else {
			// Le dossier existe, vérifions s'il est vide
			isEmpty, err := isDirEmpty(urlsDir)
			if err != nil {
				log.Printf("Erreur lors de la vérification du dossier urls: %v", err)
			}

			if isEmpty {
				log.Printf("Le dossier urls existe mais est vide")
				shouldRunStep4 = true
			} else {
				log.Printf("Le dossier urls contient déjà des fichiers, étape 4 considérée comme terminée")
			}
		}
	} else {
		log.Printf("Le fichier urls_extracted.txt n'existe pas ou est vide, étape 4 impossible")
	}

	if shouldRunStep4 {
		// Nettoyage des URLs avant l'étape 4
		log.Println("Nettoyage des URLs extraites...")
		if err := cleanExtractedUrls(outputsDir); err != nil {
			log.Fatalf("Erreur lors du nettoyage des URLs : %v", err)
		}

		log.Println("Étape 4 : Analyse HTTP sur les URLs")
		if err := step4(outputsDir, urlsDir); err != nil {
			log.Fatalf("Erreur à l'étape 4 : %v", err)
		}
	} else {
		log.Println("Étape 4 déjà complétée, reprise...")
	}

	log.Println("Reconnaissance terminée.")
}

// step1 lance en parallèle les outils de collecte et fusionne les résultats
func step1(domain, outputsDir string) error {
	// Définition des commandes et des fichiers de sortie
	tools := []struct {
		name       string
		cmd        string
		args       []string
		outputFile string
	}{
		{
			name:       "findomain",
			cmd:        "findomain",
			args:       []string{"-t", domain, "-u", filepath.Join(outputsDir, "subdomains_findomain.txt")},
			outputFile: filepath.Join(outputsDir, "subdomains_findomain.txt"),
		},
		{
			name:       "assetfinder",
			cmd:        "assetfinder",
			args:       []string{"--subs-only", domain},
			outputFile: filepath.Join(outputsDir, "subdomains_assetfinder.txt"),
		},
		{
			name:       "subfinder",
			cmd:        "subfinder",
			args:       []string{"-d", domain, "-o", filepath.Join(outputsDir, "subdomains_subfinder.txt")},
			outputFile: filepath.Join(outputsDir, "subdomains_subfinder.txt"),
		},
	}

	var wg sync.WaitGroup
	errChan := make(chan error, len(tools))

	// Exécution parallèle de chaque commande
	for _, tool := range tools {
		wg.Add(1)
		go func(t struct {
			name       string
			cmd        string
			args       []string
			outputFile string
		}) {
			defer wg.Done()
			log.Printf("Lancement de %s...", t.name)
			// Pour assetfinder, rediriger la sortie vers le fichier car il ne supporte pas -o
			if t.name == "assetfinder" {
				cmd := exec.Command(t.cmd, t.args...)
				out, err := cmd.Output()
				if err != nil {
					errChan <- fmt.Errorf("%s error: %v", t.name, err)
					return
				}
				if err := ioutil.WriteFile(t.outputFile, out, 0644); err != nil {
					errChan <- fmt.Errorf("écriture du résultat de %s : %v", t.name, err)
					return
				}
			} else {
				cmd := exec.Command(t.cmd, t.args...)
				if err := cmd.Run(); err != nil {
					errChan <- fmt.Errorf("%s error: %v", t.name, err)
					return
				}
			}
			log.Printf("%s terminé.", t.name)
		}(tool)
	}
	wg.Wait()
	close(errChan)
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	// Fusionner tous les fichiers de sous-domaines et supprimer les doublons
	mergedFile := filepath.Join(outputsDir, "subdomains_merged.txt")
	mergedSet := make(map[string]bool)
	files := []string{
		filepath.Join(outputsDir, "subdomains_findomain.txt"),
		filepath.Join(outputsDir, "subdomains_assetfinder.txt"),
		filepath.Join(outputsDir, "subdomains_subfinder.txt"),
	}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			log.Printf("Attention, impossible d'ouvrir %s : %v", file, err)
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				mergedSet[line] = true
			}
		}
		f.Close()
	}
	var mergedLines []string
	for sub := range mergedSet {
		mergedLines = append(mergedLines, sub)
	}
	if err := ioutil.WriteFile(mergedFile, []byte(strings.Join(mergedLines, "\n")), 0644); err != nil {
		return fmt.Errorf("écriture du fichier fusionné : %v", err)
	}
	log.Printf("Sous-domaines fusionnés dans %s", mergedFile)
	return nil
}

// step2 analyse les codes HTTP sur les sous-domaines avec httpx
func step2(outputsDir string) error {
	mergedFile := filepath.Join(outputsDir, "subdomains_merged.txt")
	f, err := os.Open(mergedFile)
	if err != nil {
		return fmt.Errorf("ouverture de %s : %v", mergedFile, err)
	}
	defer f.Close()
	var subdomains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Utilisation de httpx en lui passant la liste via -l
	cmd := exec.Command("/home/yau/go/bin/httpx", "-l", mergedFile, "-sc", "-nc")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("erreur httpx : %v", err)
	}

	// Traitement de la sortie de httpx pour grouper par code HTTP
	statusMap := make(map[string][]string)
	scanner = bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		url := parts[0]
		// Extraction du code HTTP entre crochets
		status := strings.Trim(parts[len(parts)-1], "[]")
		statusMap[status] = append(statusMap[status], url)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Écriture des résultats dans des fichiers explicites
	for code, urls := range statusMap {
		filename := filepath.Join(outputsDir, fmt.Sprintf("subdomains_status_%s.txt", code))
		content := strings.Join(urls, "\n")
		if err := ioutil.WriteFile(filename, []byte(content), 0644); err != nil {
			return fmt.Errorf("écriture pour le code %s : %v", code, err)
		}
		log.Printf("%d sous-domaines avec le code %s enregistrés dans %s", len(urls), code, filename)
	}
	return nil
}

// step3 extrait les URLs associées en utilisant gau et gère le traitement des domaines
func step3(outputsDir string) error {
	// Define the file path for extracted URLs
	urlsExtractedFile := filepath.Join(outputsDir, "urls_extracted.txt")

	// Ensure the directory for the extracted URLs file exists
	if err := os.MkdirAll(outputsDir, 0755); err != nil {
		return fmt.Errorf("erreur lors de la création du répertoire de sortie : %v", err)
	}

	// Find all files with a _status suffix
	statusFiles, err := filepath.Glob(filepath.Join(outputsDir, "*_status_*.txt"))
	if err != nil {
		return fmt.Errorf("erreur lors de la recherche des fichiers _status : %v", err)
	}

	for _, statusFile := range statusFiles {
		// Create a corresponding progress file for each status file
		progressFile := statusFile + ".progress"

		// Read subdomains from the status file
		data, err := ioutil.ReadFile(statusFile)
		if err != nil {
			return fmt.Errorf("erreur lors de la lecture du fichier %s : %v", statusFile, err)
		}

		lines := strings.Split(string(data), "\n")

		// Read the last processed index from the progress file
		var lastProcessedIndex int
		if _, err := os.Stat(progressFile); err == nil {
			content, err := ioutil.ReadFile(progressFile)
			if err == nil {
				fmt.Sscanf(string(content), "%d", &lastProcessedIndex)
			}
		}

		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for i, line := range lines {
			if i < lastProcessedIndex {
				continue // Skip already processed subdomains
			}

			rawURL := strings.TrimSpace(line)
			if rawURL == "" {
				continue
			}

			// Add https prefix if necessary
			if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
				rawURL = "https://" + rawURL
			}

			// Validate the URL
			parsedURL, err := url.Parse(rawURL)
			if err != nil || parsedURL.Host == "" {
				fmt.Printf("⚠️ URL invalide ignorée : %s\n", rawURL)
				continue
			}

			// Execute gau to extract historical URLs
			fmt.Printf("🔍 Extraction des URLs historiques pour : %s\n", parsedURL.Host)
			gauCmd := exec.Command("sh", "-c", fmt.Sprintf("gau %s --providers wayback,commoncrawl,otx,urlscan", parsedURL.Host))
			gauOutput, err := gauCmd.Output()
			if err != nil {
				fmt.Printf("❌ Erreur lors de l'exécution de gau pour %s : %v\n", parsedURL.Host, err)
				continue
			}

			// Add extracted URLs to the file
			extractedUrls := strings.Split(string(gauOutput), "\n")
			var validUrls []string
			for _, url := range extractedUrls {
				if strings.TrimSpace(url) != "" { // Ignore empty lines
					validUrls = append(validUrls, url)
				}
			}

			// Write extracted URLs to the file
			if len(validUrls) > 0 {
				if err := appendToFile(urlsExtractedFile, validUrls); err != nil {
					return fmt.Errorf("erreur lors de l'écriture des URLs extraites : %v", err)
				}
			}

			// Update the progress file
			if err := ioutil.WriteFile(progressFile, []byte(fmt.Sprintf("%d", i+1)), 0644); err != nil {
				return fmt.Errorf("erreur lors de la mise à jour du fichier de progression : %v", err)
			}
		}
	}

	return nil
}

// appendToFile ajoute des lignes à un fichier
func appendToFile(filename string, lines []string) error {
	// Open the file in append mode, create it if it doesn't exist
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// step4 analyse les URLs extraites avec httpx et range les résultats dans urlsDir
func step4(outputsDir, urlsDir string) error {
	urlsFile := filepath.Join(outputsDir, "urls_extracted.txt")
	progressFile := filepath.Join(outputsDir, "urls_progress.txt")

	// Check if the urlsFile exists before proceeding
	if _, err := os.Stat(urlsFile); os.IsNotExist(err) {
		return fmt.Errorf("le fichier %s n'existe pas", urlsFile)
	}

	// Ensure the urlsDir exists
	if err := os.MkdirAll(urlsDir, 0755); err != nil {
		return fmt.Errorf("erreur lors de la création du répertoire des URLs : %v", err)
	}

	// Check if urlsDir is empty
	isEmpty, err := isDirEmpty(urlsDir)
	if err != nil {
		return fmt.Errorf("erreur lors de la vérification du répertoire des URLs : %v", err)
	}

	// Determine last processed line
	lastProcessedLine := 0
	if _, err := os.Stat(progressFile); err == nil {
		content, err := ioutil.ReadFile(progressFile)
		if err == nil {
			fmt.Sscanf(string(content), "%d", &lastProcessedLine)
			log.Printf("Reprise du traitement des URLs à partir de la ligne %d", lastProcessedLine)
		}
	}

	// Count total lines in file for progress reporting
	totalLines, err := countLines(urlsFile)
	if err != nil {
		log.Printf("Erreur lors du comptage des lignes: %v", err)
	} else {
		log.Printf("Traitement du fichier contenant %d URLs", totalLines)
	}

	// If empty directory and resume info exists, process files
	if isEmpty || lastProcessedLine > 0 {
		log.Println("Lancement du traitement des URLs...")

		// Process in batches to avoid command line limits
		batchSize := 10000
		tempDir := filepath.Join(outputsDir, "temp_batches")
		os.MkdirAll(tempDir, 0755)

		// Create status maps to accumulate results
		statusMap := make(map[string][]string)
		processedCount := lastProcessedLine

		// Open file and skip to last processed line
		file, err := os.Open(urlsFile)
		if err != nil {
			return fmt.Errorf("erreur lors de l'ouverture du fichier URLs: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		// Skip already processed lines
		for i := 0; i < lastProcessedLine && scanner.Scan(); i++ {
			// Just advance the scanner
		}

		// Process remaining lines in batches
		currentBatch := []string{}
		batchNum := 1

		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url == "" {
				continue
			}

			currentBatch = append(currentBatch, url)
			processedCount++

			// When batch is full or at EOF, process it
			if len(currentBatch) >= batchSize || processedCount >= totalLines {
				if len(currentBatch) > 0 {
					log.Printf("Traitement du lot %d (%d URLs, progression: %.2f%%)",
						batchNum, len(currentBatch), float64(processedCount)*100/float64(totalLines))

					// Create temporary file for this batch
					batchFile := filepath.Join(tempDir, fmt.Sprintf("batch_%d.txt", batchNum))
					if err := ioutil.WriteFile(batchFile, []byte(strings.Join(currentBatch, "\n")), 0644); err != nil {
						return fmt.Errorf("erreur lors de l'écriture du fichier batch: %v", err)
					}

					// Process this batch with httpx
					results, err := processURLBatch(batchFile)
					if err != nil {
						log.Printf("Erreur lors du traitement du lot %d: %v", batchNum, err)
					} else {
						// Merge results into status map
						for status, urls := range results {
							statusMap[status] = append(statusMap[status], urls...)
						}
					}

					// Clean up batch file
					os.Remove(batchFile)

					// Update progress file
					if err := ioutil.WriteFile(progressFile, []byte(fmt.Sprintf("%d", processedCount)), 0644); err != nil {
						log.Printf("Erreur lors de la mise à jour du fichier de progression: %v", err)
					}

					// Reset batch
					currentBatch = []string{}
					batchNum++
				}
			}
		}

		if err := scanner.Err(); err != nil {
			return fmt.Errorf("erreur lors de la lecture du fichier URLs: %v", err)
		}

		// Write final results to files in urlsDir
		for code, urls := range statusMap {
			filename := filepath.Join(urlsDir, fmt.Sprintf("urls_status_%s.txt", code))

			// Append to existing file if it exists
			if _, err := os.Stat(filename); err == nil {
				existingURLs, err := ioutil.ReadFile(filename)
				if err == nil {
					existingURLsSet := make(map[string]bool)
					for _, url := range strings.Split(string(existingURLs), "\n") {
						if url = strings.TrimSpace(url); url != "" {
							existingURLsSet[url] = true
						}
					}

					// Add only unique URLs
					uniqueURLs := []string{}
					for _, url := range urls {
						if !existingURLsSet[url] {
							uniqueURLs = append(uniqueURLs, url)
						}
					}

					// Append to file
					if len(uniqueURLs) > 0 {
						f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0644)
						if err == nil {
							_, err = f.WriteString("\n" + strings.Join(uniqueURLs, "\n"))
							f.Close()
							if err == nil {
								log.Printf("Ajout de %d nouvelles URLs avec code %s dans %s", len(uniqueURLs), code, filename)
							}
						}
					}
				}
			} else {
				// Create new file
				content := strings.Join(urls, "\n")
				if err := ioutil.WriteFile(filename, []byte(content), 0644); err != nil {
					return fmt.Errorf("écriture pour le code %s: %v", code, err)
				}
				log.Printf("%d URLs avec le code %s enregistrées dans %s", len(urls), code, filename)
			}
		}

		// Clean up temp directory
		os.RemoveAll(tempDir)

		// If process completed, remove progress file
		if processedCount >= totalLines {
			os.Remove(progressFile)
			log.Println("Traitement des URLs terminé.")
		} else {
			log.Printf("Traitement interrompu à %d/%d URLs (%.2f%%)",
				processedCount, totalLines, float64(processedCount)*100/float64(totalLines))
		}
	} else {
		log.Println("Le répertoire des URLs n'est pas vide, étape 4 déjà complétée.")
	}

	return nil
}

// processURLBatch traite un lot d'URLs avec httpx et retourne les résultats groupés par code HTTP
func processURLBatch(batchFile string) (map[string][]string, error) {
	cmd := exec.Command("/home/yau/go/bin/httpx", "-l", batchFile, "-nc", "-sc")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("erreur httpx sur les URLs: %v", err)
	}

	statusMap := make(map[string][]string)
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		url := parts[0]
		status := strings.Trim(parts[len(parts)-1], "[]")
		statusMap[status] = append(statusMap[status], url)
	}

	return statusMap, scanner.Err()
}

// countLines compte le nombre de lignes non vides dans un fichier
func countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineCount := 0

	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lineCount++
		}
	}

	return lineCount, scanner.Err()
}

// Helper function to check if a directory is empty
func isDirEmpty(dir string) (bool, error) {
	f, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()

	// Read directory entries
	_, err = f.Readdirnames(1) // Or f.Readdir(1)
	if err == io.EOF {
		return true, nil // Directory is empty
	}
	return false, err // Directory is not empty or error occurred
}

// cleanExtractedUrls supprime les doublons et les URLs non valides du fichier urls_extracted.txt
func cleanExtractedUrls(outputsDir string) error {
	urlsFile := filepath.Join(outputsDir, "urls_extracted.txt")
	cleanedFile := filepath.Join(outputsDir, "urls_cleaned.txt")

	// Ouvrir le fichier des URLs extraites
	file, err := os.Open(urlsFile)
	if err != nil {
		return fmt.Errorf("impossible d'ouvrir le fichier des URLs extraites : %v", err)
	}
	defer file.Close()

	// Map pour stocker les URLs uniques
	uniqueUrls := make(map[string]bool)

	// Scanner pour lire le fichier ligne par ligne
	scanner := bufio.NewScanner(file)
	// Augmenter la taille du buffer pour gérer les grandes lignes
	const maxCapacity = 512 * 1024 // 512 KB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	validCount := 0
	duplicateCount := 0
	invalidCount := 0

	// Lire chaque ligne
	for scanner.Scan() {
		urlStr := strings.TrimSpace(scanner.Text())
		if urlStr == "" {
			continue
		}

		// Valider l'URL
		parsedURL, err := url.Parse(urlStr)
		if err != nil || parsedURL.Host == "" || parsedURL.Scheme == "" {
			invalidCount++
			continue
		}

		// Vérifier si cette URL a déjà été vue
		if _, exists := uniqueUrls[urlStr]; exists {
			duplicateCount++
			continue
		}

		// Ajouter l'URL à notre map
		uniqueUrls[urlStr] = true
		validCount++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("erreur lors de la lecture du fichier : %v", err)
	}

	// Écrire les URLs uniques dans un nouveau fichier
	file, err = os.Create(cleanedFile)
	if err != nil {
		return fmt.Errorf("impossible de créer le fichier nettoyé : %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for url := range uniqueUrls {
		if _, err := writer.WriteString(url + "\n"); err != nil {
			return fmt.Errorf("erreur lors de l'écriture des URLs nettoyées : %v", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("erreur lors de la finalisation de l'écriture : %v", err)
	}

	// Remplacer l'ancien fichier par le nouveau
	if err := os.Rename(cleanedFile, urlsFile); err != nil {
		return fmt.Errorf("impossible de remplacer l'ancien fichier : %v", err)
	}

	log.Printf("Nettoyage terminé: %d URLs valides, %d doublons supprimés, %d URLs invalides ignorées",
		validCount, duplicateCount, invalidCount)

	return nil
}
