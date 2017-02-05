package com.etfbl.ssoproject.idp.model;

import org.springframework.data.repository.CrudRepository;

import java.util.List;

/**
 * Created by Rajo on 19.4.2016..
 */
public interface TargetHostDao extends CrudRepository<TargetHost, Long> {

    public TargetHost findByUrl(String url);
}
