package ik.ghidranesrom.loader.exception;

public class NesRomEofException extends NesRomException {
	public NesRomEofException() {
		super("Encountered unexpected EOF when reading NES ROM");
	}
}
