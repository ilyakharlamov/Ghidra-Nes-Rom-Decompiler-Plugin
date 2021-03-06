find build -type f -name '*.zip' | xargs -I ^ rm '^'
export GHIDRA_INSTALL_DIR=/Applications/ghidra_10.0.3_PUBLIC/
gradle assemble
find build -type f -name '*.zip' | xargs -I ^ unzip -c ^ mnt/extension.properties
find build -type f -name '*.zip' | xargs -I ^ cp ^ "$GHIDRA_INSTALL_DIR/Extensions/Ghidra/"
cp build/libs/mnt.jar /tilda_dot_ghidra/.ghidra_10.0.3_PUBLIC/Extensions/mnt/lib/mnt.jar 
