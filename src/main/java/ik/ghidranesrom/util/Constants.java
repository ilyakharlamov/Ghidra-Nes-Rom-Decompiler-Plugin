package ik.ghidranesrom.util;

import com.google.common.collect.ImmutableList;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class Constants {
    public static ImmutableList<BrandedAddress> brandedAddresses = ImmutableList.<BrandedAddress>builder()
            .add(new BrandedAddress(0x2000, 1, "PPUCTRL"))
            .add(new BrandedAddress(0x2001, 1, "PPUMASK"))
            .add(new BrandedAddress(0x2002, 1, "PPUSTATUS"))
            .add(new BrandedAddress(0x2003, 1, "OAMADDR"))
            .add(new BrandedAddress(0x2004, 1, "OAMDATA"))
            .add(new BrandedAddress(0x2005, 1, "PPUSCROLL"))
            .add(new BrandedAddress(0x2006, 1, "PPUADDR"))
            .add(new BrandedAddress(0x2007, 1, "PPUDATA"))
            .add(new BrandedAddress(0x4000, 4, "APU_SND_SQUARE1_REG"))
            .add(new BrandedAddress(0x4004, 4, "APU_SND_SQUARE2_REG"))
            .add(new BrandedAddress(0x4008, 4, "APU_SND_TRIANGLE_REG"))
            .add(new BrandedAddress(0x400c, 2, "APU_NOISE_REG"))
            .add(new BrandedAddress(0x400e, 1, "APU_NOISE_REG_FREQUENCY_2"))
            .add(new BrandedAddress(0x400f, 1, "APU_NOISE_REG_FREQUENCY_AND_TIME_3"))
            .add(new BrandedAddress(0x4010, 4, "APU_DELTA_REG"))
            .add(new BrandedAddress(0x4014, 1, "OAMDMA"))
            .add(new BrandedAddress(0x4015, 1, "APU_MASTERCTRL_REG"))
            .add(new BrandedAddress(0x4016, 1, "JOYPAD_PORT1"))
            .add(new BrandedAddress(0x4017, 1, "JOYPAD_PORT2"))
            .build();

    public static Map<Long, BrandedAddress> brandedAddressImmutableMap =
            brandedAddresses.stream().collect(Collectors.toMap(x -> Long.valueOf(x.getAddr()), Function.identity()));
}
