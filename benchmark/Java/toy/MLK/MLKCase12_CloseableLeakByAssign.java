import java.io.FileInputStream;
import java.io.InputStream;

class MLKCase12_CloseableLeakByAssign {
    public void run(String path) throws Exception {
        InputStream in;
        in = new FileInputStream(path);
        System.out.println(in);
    }
}
