package com.etfbl.ssoproject.idp.model;

import org.springframework.data.repository.CrudRepository;

import java.util.List;

/**
 * Created by Rajo on 19.4.2016..
 */
public interface TargetAuthorityDao extends CrudRepository<TargetAuthority, Long> {

    public List<TargetAuthority> findByUsernameAndTargetHost(String username, TargetHost targetHost);
}
