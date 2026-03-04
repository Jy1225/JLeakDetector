import java.io.FileInputStream;
import java.io.InputStream;

class MLKCase02_CloseableClosed {
    public void run(String path) throws Exception {
        InputStream in = new FileInputStream(path);
        int value = in.read();
        if (value > 0) {
            System.out.println(value);
        }
        in.close();
    }
}
