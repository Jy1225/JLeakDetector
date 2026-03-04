import java.io.FileInputStream;
import java.io.InputStream;

class MLKCase03_TryWithResourcesSafe {
    public void run(String path) throws Exception {
        try (InputStream in = new FileInputStream(path)) {
            int value = in.read();
            if (value > 0) {
                System.out.println(value);
            }
        }
    }
}
