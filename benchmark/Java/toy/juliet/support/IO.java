package juliet.support;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Logger;

public final class IO {
    public static final Logger logger = Logger.getLogger(IO.class.getName());
    public static final boolean STATIC_FINAL_TRUE = true;
    public static final boolean STATIC_FINAL_FALSE = false;
    public static final int STATIC_FINAL_FIVE = 5;
    public static boolean staticTrue = true;
    public static boolean staticFalse = false;
    public static int staticFive = 5;

    private IO() {
    }

    public static void writeLine(String value) {
        System.out.println(value);
    }

    public static void writeLine(int value) {
        System.out.println(value);
    }

    public static void writeString(String value) {
        System.out.print(value);
    }

    public static boolean staticReturnsTrue() {
        return true;
    }

    public static boolean staticReturnsFalse() {
        return false;
    }

    public static boolean staticReturnsTrueOrFalse() {
        return (System.nanoTime() & 1L) == 0L;
    }

    public static Connection getDBConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:repoaudit:stub");
    }
}
