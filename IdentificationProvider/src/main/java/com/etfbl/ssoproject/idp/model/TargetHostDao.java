package com.etfbl.ssoproject.idp.model;

import org.springframework.data.repository.CrudRepository;

public interface TargetHostDao extends CrudRepository<TargetHost, Long> {

    public TargetHost findByUrl(String url);
}
