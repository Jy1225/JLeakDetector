import java.io.FileInputStream;
import java.io.InputStream;

class MLKCase34_ContradictoryBranchUnsat {
    public void run(String path, int level) throws Exception {
        InputStream in = new FileInputStream(path); // SRC

        if (level > 0) {           // 条件 C1
            if (level <= 0) {      // 条件 C2，与 C1 矛盾
                // 这个分支故意不 close，用于制造“看起来像泄漏”的不可达路径
                System.out.println(in.read());
            } else {
                in.close();        // 可达路径会关闭
            }
        } else {
            in.close();            // 可达路径会关闭
        }
    }
}
