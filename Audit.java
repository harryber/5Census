import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Audit {
    private BufferedWriter writer;

    public Audit(String auditFile) {
        if (auditFile == null) {
            return;
        }
        openAudit(auditFile);
    }

    public Audit() {
        openAudit(null);
    }

    public void log(String message) {
        if (writer == null) {
            return;
        }

        try {
            DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
            LocalDateTime now = LocalDateTime.now();
            writer.write(dateFormat.format(now) + " " + message + "\n");
            writer.flush();
        } catch (IOException e) {
            System.err.println("Error writing to audit log: " + e.getMessage());
        }
    }

    public void logPrint(String message) {
        log(message);
        System.out.println(message);
    }

    public void openAudit(String auditFilePath) {
        try {
            writer = new BufferedWriter(new FileWriter(auditFilePath, true));
        } catch (IOException e) {
            System.err.println("Error creating audit log: " + e.getMessage());
        }
    }

    public void closeAudit() {
        try {
            writer.close();
        } catch (IOException e) {
            System.err.println("Error closing audit log: " + e.getMessage());
        }
    }
}
