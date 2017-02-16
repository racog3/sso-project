package com.etfbl.ssoproject.idp.model;

import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface TargetAuthorityDao extends CrudRepository<TargetAuthority, Long> {

    public List<TargetAuthority> findByUsernameAndTargetHost(String username, TargetHost targetHost);
}
