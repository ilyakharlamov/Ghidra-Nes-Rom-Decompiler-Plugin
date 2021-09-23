package ik.ghidranesrom.util;

public class BrandedAddress {
    private final int address;
    private final int size;
    private final String name;

    public BrandedAddress(int address, int size, String name) {
        this.address = address;
        this.size = size;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public long getSize() {
        return size;
    }

    public int getAddr() {
        return address;
    }
}
