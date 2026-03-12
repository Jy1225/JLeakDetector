package juliet.support;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class AbstractTestCaseServlet extends AbstractTestCase {
    public abstract void bad(HttpServletRequest request, HttpServletResponse response) throws Throwable;

    public abstract void good(HttpServletRequest request, HttpServletResponse response) throws Throwable;

    @Override
    public final void bad() throws Throwable {
        bad(null, null);
    }

    @Override
    public void good() throws Throwable {
        good(null, null);
    }
}
