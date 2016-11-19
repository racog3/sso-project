package com.etfbl.ssoproject.idp.model;

import org.springframework.data.repository.CrudRepository;

/**
 * Created by Rajo on 19.4.2016..
 */
public interface CredentialDao extends CrudRepository<Credential, Long> {
    public Credential findByUsername(String username);
}
