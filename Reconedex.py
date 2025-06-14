import os
import argparse
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

# ANSI color codes
def color_info(text: str) -> str:
    # Green for info values (extensions or parameters)
    return f"\033[32m{text}\033[0m"

class Extractor:
    """
    Interface for info extractors.
    Each extractor must define a `name` and implement `extract(url)`.
    """
    name = "base"

    def extract(self, url: str) -> list[str]:
        raise NotImplementedError

class ExtensionExtractor(Extractor):
    name = "extensions"

    def extract(self, url: str) -> list[str]:
        path = urlparse(url).path
        if "." in path:
            ext = os.path.splitext(path)[1].lower().lstrip('.')
            if ext:
                return [ext]
        return []

class ParamExtractor(Extractor):
    name = "parameters"

    def extract(self, url: str) -> list[str]:
        qs = urlparse(url).query
        params = parse_qs(qs)
        return list(params.keys())


def load_urls_by_status(input_dir: str) -> dict[str, list[str]]:
    data = {}
    for fname in os.listdir(input_dir):
        if not fname.startswith("urls_status_") or not fname.endswith(".txt"):
            continue
        code = fname[len("urls_status_"):-4]
        path = os.path.join(input_dir, fname)
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip()]
        except Exception:
            with open(path, 'r', encoding='latin-1', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip()]
        data[code] = urls
    return data


def aggregate(extractors: list[Extractor], urls_by_status: dict[str, list[str]]) -> dict:
    agg = {ext.name: defaultdict(lambda: defaultdict(set)) for ext in extractors}
    for status, urls in urls_by_status.items():
        for url in urls:
            for ext in extractors:
                for info in ext.extract(url):
                    agg[ext.name][info][status].add(url)
    return agg


def write_outputs(aggregation: dict, output_dir: str):
    for extractor_name, infos in aggregation.items():
        ext_dir = os.path.join(output_dir, extractor_name)
        os.makedirs(ext_dir, exist_ok=True)

        if extractor_name == 'parameters':
            # For parameters, one example URL per parameter per status
            status_param_example = defaultdict(dict)
            for param, status_map in infos.items():
                for status, urls in status_map.items():
                    example = next(iter(urls)) if urls else ''
                    status_param_example[status][param] = example

            for status, param_map in status_param_example.items():
                fname = f"status_{status}.txt"
                path = os.path.join(ext_dir, fname)
                with open(path, 'w', encoding='utf-8') as f:
                    for param in sorted(param_map):
                        colored = color_info(param)
                        f.write(f"{colored}\t{param_map[param]}\n")
        else:
            # For extensions, list every URL per extension per status
            status_ext_urls = defaultdict(lambda: defaultdict(set))
            for ext_val, status_map in infos.items():
                for status, urls in status_map.items():
                    status_ext_urls[status][ext_val].update(urls)

            for status, ext_map in status_ext_urls.items():
                fname = f"status_{status}.txt"
                path = os.path.join(ext_dir, fname)
                with open(path, 'w', encoding='utf-8') as f:
                    for ext_val in sorted(ext_map):
                        colored = color_info(ext_val)
                        for url in sorted(ext_map[ext_val]):
                            f.write(f"{colored}\t{url}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Extract info from URLs grouped by HTTP status."
    )
    parser.add_argument(
        "--target-dir", "-t",
        dest="target_dir",
        required=True,
        help="Directory containing 'urls' folder; an 'info' folder will be created inside"
    )
    args = parser.parse_args()

    input_dir = os.path.join(args.target_dir, "urls")
    output_dir = os.path.join(args.target_dir, "info")
    os.makedirs(output_dir, exist_ok=True)

    extractors = [ExtensionExtractor(), ParamExtractor()]
    urls_by_status = load_urls_by_status(input_dir)
    aggregation = aggregate(extractors, urls_by_status)
    write_outputs(aggregation, output_dir)


if __name__ == "__main__":
    main()
