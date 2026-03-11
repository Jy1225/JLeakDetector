package testcasesupport;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Logger;

public final class IO {
    public static final Logger logger = Logger.getLogger(IO.class.getName());

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

    public static Connection getDBConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:repoaudit:stub");
    }
}
