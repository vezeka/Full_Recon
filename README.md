''ORDER TO RUN SCRIPT''

1)Reconedex.go

-domain is the wildcard you want to test 
-target is the ouptut directory name 

go run Reconedex.go -domain exemple.com -target exemple

2)Reconedex.py

-t declare the path of the name that you enter in target 

python Reconedex.py -t exemple 

in te same rep you will see a new directory name info with param and extension of the url sorted by status code and regrouped in the file 



3)xssdetection is a framework that implemented to be used after you run the Reconedex.py

-before start make sur to add your payload xss list in the payload.txt file

-go in info/parameter/* and list all of your file 

-now use ./run.sh and enter the path , it will automaticly scan and run xss testing on reflected parameter 

-after the scan end it will send a data folder in the previous path you enter with all information



I will add new feature soon like encoding payload , capacity of context comprehension , waf bypass and a better configuration before the script start
