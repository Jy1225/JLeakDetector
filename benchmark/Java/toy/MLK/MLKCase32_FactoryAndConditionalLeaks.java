import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.net.SocketFactory;

class MLKCase32_FactoryAndConditionalLeaks {
    public void run(Path dataFile, String host, int port) throws Exception {
        // Leak path A: source from factory method Files.newInputStream(...)
        InputStream fileStream = buildFileStream(dataFile);
        analyzeData(fileStream, 0);

        // Leak path B(fixed): source from factory method createSocket(...)
        Socket socket = buildSocket(host, port);
        sendPing(socket, false);
    }

    private InputStream buildFileStream(Path path) throws IOException {
        InputStream in = Files.newInputStream(path);
        if (path.toString().endsWith(".log")) {
            System.out.println("log input");
        }
        return in;
    }

    private void analyzeData(InputStream in, int level) throws IOException {
        int b = in.read();
        if (b > 0 && level > 10) {
            in.close();
        } else {
            // Non-ownership API usage only; still should be considered leak.
            System.out.println("first byte = " + b);
            System.out.println("stream handle = " + in);
        }
    }

    private Socket buildSocket(String host, int port) throws IOException {
        Socket socket = SocketFactory.getDefault().createSocket(host, port);
        if (port == 443) {
            System.out.println("tls-like port");
        }
        return socket;
    }

    private void sendPing(Socket socket, boolean closeAfterSend) throws IOException {
        socket.getOutputStream().write(1);
        socket.getOutputStream().flush();
        //socket.close();
    }
}
