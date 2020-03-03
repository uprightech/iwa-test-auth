package org.gluu.test.spnego.auth;


public class SpnegoConfiguration {
    
    private SpnegoServerAuthMethod serverAuthMethod;
    private String keyTabFile;
    private String serverUsername;
    private String serverPassword;
    private String kerberosConfigFile;
    private String loginConfigFile;
    private String loginModule;


    public SpnegoConfiguration() {

        this.serverAuthMethod = SpnegoServerAuthMethod.USE_KEYTAB_FILE;
    }


    public SpnegoServerAuthMethod getServerAuthMethod() {

        return this.serverAuthMethod;
    }

    public void setServerAuthMethod(SpnegoServerAuthMethod serverAuthMethod) {

        this.serverAuthMethod = serverAuthMethod;
    }

    public String getKeyTabFile() {

        return this.keyTabFile;
    }

    public void setKeyTabFile(String keyTabFile) {

        this.keyTabFile = keyTabFile;
    }

    public String getServerUsername() {

        return this.serverUsername;
    }

    public void setServerUsername(String serverUsername) {

        this.serverUsername = serverUsername;
    }

    public String getServerPassword() {

        return this.serverPassword;
    }

    public void setServerPassword(String serverPassword) {

        this.serverPassword = serverPassword;
    }

    public String getKerberosConfigFile() {

        return this.kerberosConfigFile;
    }

    public void setKerberosConfigFile(String kerberosConfigFile) {

        this.kerberosConfigFile = kerberosConfigFile;
    }

    public boolean hasKerberosConfigFile() {

        return this.kerberosConfigFile != null && !this.kerberosConfigFile.isEmpty();
    }

    public String getLoginConfigFile() {

        return this.loginConfigFile;
    }

    public void setLoginConfigFile(String loginConfigFile) {

        this.loginConfigFile = loginConfigFile;
    }

    public boolean hasLoginConfigFile() {

        return this.loginConfigFile !=null && !this.loginConfigFile.isEmpty();
    }

    public String getLoginModule() {

        return this.loginModule;
    }

    public void setLoginModule(String loginModule) {

        this.loginModule = loginModule;
    }

}