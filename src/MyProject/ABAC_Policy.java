
package MyProject;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


public class ABAC_Policy {
    
    private String policyID;
    private String subject;
    private String action;
    private String resource;
    private String environment;
    private String effect;
public ABAC_Policy(String policyID, String subject, String action, String resource, String environment, String effect) {
this.policyID = policyID;
this.subject = subject;
this.action = action;
this.resource = resource;
this.environment = environment;
this.effect = effect;
}


public static List<ABAC_Policy> readPoliciesFromCSV(String filePath) {
    List<ABAC_Policy> policies = new ArrayList<>();
    try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
    String line;
    while ((line = br.readLine()) != null) {
        String[] values = line.split(",");
        if (values.length == 6) {
            ABAC_Policy policy = new ABAC_Policy(values[0], values[1], values[2], values[3], values[4], values[5]);
            policies.add(policy);
        } else {
                System.err.println("Invalid CSV format: " + line);
            }
        }
        } catch (IOException e) {
            e.printStackTrace();
        }
    return policies;
    }


public String getPolicyID() { return policyID; }
public String getSubject() { return subject; }
public String getAction() { return action; }
public String getResource() { return resource; }
public String getEnvironment() { return environment; }
public String getEffect() { return effect; }


public static boolean evaluateAccess(String subject, String action, String resource, String environment, List<ABAC_Policy> policies) {
    for (ABAC_Policy policy : policies) {
        if (policy.getSubject().equals(subject) &&
            policy.getAction().equals(action) &&
            policy.getResource().equals(resource) &&
            policy.getEnvironment().equals(environment)) {
            return policy.getEffect().equals("allow");
        }
    }
    return false;
}

}
