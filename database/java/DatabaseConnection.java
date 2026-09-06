import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * MySQL connection utility for services that need to access encrypted cloud-data metadata.
 * Configuration comes from environment variables; no credentials belong in source code.
 */
public final class DatabaseConnection {
    private static final int DEFAULT_PORT = 3306;
    private static final int LOGIN_TIMEOUT_SECONDS = 10;

    private final String jdbcUrl;
    private final String user;
    private final String password;

    private DatabaseConnection(String jdbcUrl, String user, String password) {
        this.jdbcUrl = jdbcUrl;
        this.user = user;
        this.password = password;
    }

    /** Builds a connection factory from DB_HOST, DB_PORT, DB_NAME, DB_USER, and DB_PASSWORD. */
    public static DatabaseConnection fromEnvironment() {
        String host = environmentOrDefault("DB_HOST", "127.0.0.1");
        int port = parsePort(environmentOrDefault("DB_PORT", String.valueOf(DEFAULT_PORT)));
        String database = environmentOrDefault("DB_NAME", "cloud_security");
        String user = environmentOrDefault("DB_USER", "cloud_app");
        String password = System.getenv("DB_PASSWORD");

        if (password == null || password.isBlank()) {
            throw new IllegalStateException("DB_PASSWORD must be set.");
        }

        // TLS is required by default. Use DB_SSL_DISABLED=true only for local development.
        boolean sslDisabled = Boolean.parseBoolean(environmentOrDefault("DB_SSL_DISABLED", "false"));
        String jdbcUrl = "jdbc:mysql://" + host + ":" + port + "/" + database
                + "?useSSL=" + !sslDisabled + "&requireSSL=" + !sslDisabled
                + "&serverTimezone=UTC";
        return new DatabaseConnection(jdbcUrl, user, password);
    }

    public Connection connect() throws SQLException {
        DriverManager.setLoginTimeout(LOGIN_TIMEOUT_SECONDS);
        return DriverManager.getConnection(jdbcUrl, user, password);
    }

    /** Executes a minimal query and closes all JDBC resources. */
    public boolean isHealthy() {
        try (Connection connection = connect();
             PreparedStatement statement = connection.prepareStatement("SELECT 1");
             ResultSet result = statement.executeQuery()) {
            return result.next() && result.getInt(1) == 1;
        } catch (SQLException error) {
            return false;
        }
    }

    private static String environmentOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private static int parsePort(String value) {
        try {
            int port = Integer.parseInt(value);
            if (port < 1 || port > 65535) {
                throw new NumberFormatException();
            }
            return port;
        } catch (NumberFormatException error) {
            throw new IllegalStateException("DB_PORT must be an integer between 1 and 65535.", error);
        }
    }

    public static void main(String[] args) {
        DatabaseConnection database = DatabaseConnection.fromEnvironment();
        System.out.println(database.isHealthy() ? "MySQL connection is healthy." : "MySQL is unavailable.");
    }
}
