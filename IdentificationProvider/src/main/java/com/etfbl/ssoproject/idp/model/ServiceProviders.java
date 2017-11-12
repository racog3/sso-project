package com.etfbl.ssoproject.idp.model;

import org.apache.commons.collections.map.HashedMap;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Map;

@Component
@Scope(value="session", proxyMode= ScopedProxyMode.TARGET_CLASS)
public class ServiceProviders implements Serializable {
    private Map<String, TargetHost> serviceProvidersMap = new HashedMap();

    public void addServiceProvider(String sessionIndex, TargetHost targetHost) {
        serviceProvidersMap.put(sessionIndex, targetHost);
    }

    public Map<String, TargetHost> getServiceProviders() {
        return serviceProvidersMap;
    }
}
