import java.util.HashMap;
import java.util.Map;
import ghidra.app.util.headless.HeadlessScript;

public class DisableWindowsResourceReferenceAnalyzer extends HeadlessScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("No current program available; skipping analyzer configuration.");
            return;
        }

        Map<String, String> options = new HashMap<>();
        options.put("Windows x86 PE Resource Reference", "false");
        setAnalysisOptions(currentProgram, options);

        println("Disabled Windows x86 PE Resource Reference analyzer for this headless session.");
    }
}
