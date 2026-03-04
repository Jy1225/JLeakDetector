import java.io.FileInputStream;
import java.io.InputStream;

class MLKCase17_ConditionalCloseLeak {
    public void run(String path, boolean closeIt) throws Exception {
        InputStream in = new FileInputStream(path);
        if (closeIt) {
            in.close();
        }
    }
}
