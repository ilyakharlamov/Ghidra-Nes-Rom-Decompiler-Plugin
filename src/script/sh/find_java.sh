set -Eeu 

find "$GHIDRA_INSTALL_DIR" -type f -name '*.jar' | while read -r jarfpath
do
   unzip -l "$jarfpath" | awk "NR==1{J=\$0} /$1/{print J;print}"
done
