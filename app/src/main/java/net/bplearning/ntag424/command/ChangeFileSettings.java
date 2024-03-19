package net.bplearning.ntag424.command;

import java.io.IOException;

import net.bplearning.ntag424.CommandResult;
import net.bplearning.ntag424.DnaCommunicator;

public class ChangeFileSettings implements Command {
	public void run(DnaCommunicator communicator, int fileNum, FileSettings settings) throws IOException {
        byte[] data = settings.encodeToData();

        CommandResult result = communicator.nxpEncryptedCommand(
            (byte)0x5f,
			new byte[] { (byte) fileNum },
            data
        );
		result.throwUnlessSuccessful();
    }
}
