package burp;

public class RequestContext {
    private byte[] request;
    private byte[] response;
    private IHttpService service;
    private String comment;
    
    public RequestContext(byte[] request, IHttpService service) {
        this.request = request;
        this.service = service;
        this.response = null;
        this.comment = "";
    }
    
    public RequestContext(byte[] request, byte[] response, IHttpService service) {
        this.request = request;
        this.response = response;
        this.service = service;
        this.comment = "";
    }
    
    // Copy constructor
    public RequestContext(RequestContext other) {
        this.request = other.request != null ? other.request.clone() : null;
        this.response = other.response != null ? other.response.clone() : null;
        this.service = other.service;
        this.comment = other.comment;
    }
    
    public byte[] getRequest() {
        return request;
    }
    
    public void setRequest(byte[] request) {
        this.request = request;
    }
    
    public byte[] getResponse() {
        return response;
    }
    
    public void setResponse(byte[] response) {
        this.response = response;
    }
    
    public IHttpService getService() {
        return service;
    }
    
    public void setService(IHttpService service) {
        this.service = service;
    }
    
    public String getComment() {
        return comment;
    }
    
    public void setComment(String comment) {
        this.comment = comment;
    }
    
    public boolean hasResponse() {
        return response != null && response.length > 0;
    }
    
    public boolean hasService() {
        return service != null;
    }
    
    public String getServiceInfo() {
        if (service == null) return "No service";
        return service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
    }
}
