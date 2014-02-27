# Created by Blake Cornell, CTO, Integris Security LLC
# Integris Security Carbonator - Beta Version - v0.1
# Released under GPL Version 2 license.

if [[ -n $1 && -n $2 && -n $3 ]]
then
	SCHEME=$1
	FQDN=$2
	PORT=$3
	FOLDER=$4
	echo Launching Scan against $1://$2:$3$4
	java -jar -Xmx1024m ../burp_suite/burpsuite_pro_v1.5.21.jar $SCHEME $FQDN $PORT $FOLDER
	#java -jar -Xmx1024m -Djava.awt.headless=true burpsuite_pro_v1.5.21.jar $SCHEME $FQDN $PORT
else
	echo Usage: $0 scheme fqdn port path
	echo '    'Example: $0 http localhost 80 /folder
	echo '    Scan multiple sites: cat scheme_fqdn_port.txt | xargs -L1 '$0
fi

exit
