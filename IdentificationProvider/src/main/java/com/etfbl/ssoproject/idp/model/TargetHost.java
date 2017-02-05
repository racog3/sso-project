package com.etfbl.ssoproject.idp.model;


import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.List;

/**
 * Created by Rajo on 19.4.2016..
 */
@Entity
@Table(name = "target_hosts")
public class TargetHost {

    @Id
    @GeneratedValue
    @Column(name = "target_host_id")
    private long id;

    @NotNull
    @Column(name = "url")
    private String url;

    @NotNull
    @Column(name = "name")
    private String name;

    @OneToMany(fetch = FetchType.LAZY, mappedBy = "targetHost")
    private List<TargetAuthority> targetAuthorities;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
