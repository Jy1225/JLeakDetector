import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

class MLKCase31_InterproceduralReturnLeak {
    private int totalBytes = 0;

    public void run(String primaryPath, String backupPath, boolean useBackup)
        throws IOException {
        InputStream in = chooseStream(primaryPath, backupPath, useBackup);
        traceResource(in);
        consumeInAnotherFunction(in, false);
        function1(in);
        if (totalBytes > 2048) {
            System.out.println("large payload: " + totalBytes);
        }
        // Intentionally no close() here: leak should survive interprocedural path.
    }

    private InputStream chooseStream(String primaryPath, String backupPath, boolean useBackup)
        throws IOException {
        if (useBackup) {
            return openBackup(backupPath);
        }
        return openPrimary(primaryPath);
    }

    private InputStream openPrimary(String path) throws IOException {
        InputStream in = new FileInputStream(path);
        if (path.endsWith(".tmp")) {
            System.out.println("tmp file");
        }
        return in;
    }

    private InputStream openBackup(String backupPath) throws IOException {
        InputStream in = new FileInputStream(backupPath);
        if (backupPath.contains("daily")) {
            System.out.println("daily backup");
        }
        return in;
    }

    private void consumeInAnotherFunction(InputStream in, boolean closeAfterRead)
        throws IOException {
        int first = in.read();
        if (first >= 0) {
            totalBytes += first;
        }
        int second = in.read();
        if (second >= 0) {
            totalBytes += second;
        }
        else if (second == -1) {
            System.out.println("EOF reached");
        }
        //in.close();
    }

    private void function1(InputStream in) throws IOException {
        int var=in.read();
        function2(in);
        if(var>=0){
            in.close();
        }
    }

    private void function2(InputStream in) throws IOException {
        int var=in.read();
        function3(in);
    }

    private void function3(InputStream in) throws IOException {
        in.close();
    }

    private void traceResource(InputStream in) {
        // Non-ownership transfer call; should not hide leak.
        System.out.println("resource=" + in);
    }
}
