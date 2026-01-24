package burp;

public class AutocompleteContext {
    private final IHttpRequestResponse message;
    
    private AutocompleteContext(IHttpRequestResponse message) {
        this.message = message;
    }
    
    public static AutocompleteContext from(IHttpRequestResponse message) {
        return new AutocompleteContext(message);
    }
    
    public boolean hasService() {
        return message != null && message.getHttpService() != null;
    }
    
    public IHttpRequestResponse getMessage() {
        return message;
    }
    
    public IHttpService getService() {
        return message != null ? message.getHttpService() : null;
    }
}