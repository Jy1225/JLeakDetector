package juliet.support;

public abstract class AbstractTestCase {
    public abstract void bad() throws Throwable;

    public void good() throws Throwable {
        // No-op support stub for standalone compilation.
    }

    protected static void mainFromParent(String[] args) {
        // No-op support stub for standalone compilation.
    }
}
