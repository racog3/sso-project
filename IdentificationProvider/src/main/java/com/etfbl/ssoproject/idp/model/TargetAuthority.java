package com.etfbl.ssoproject.idp.model;


import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Entity
@Table(name = "target_authorities")
public class TargetAuthority {

    @Id
    @GeneratedValue
    @Column(name = "target_authority_id")
    private long id;

    @NotNull
    @Column(name = "username")
    private String username;

    @NotNull
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "target_host_id", nullable = false)
    private TargetHost targetHost;

    @NotNull
    @Column(name = "role")
    private String role;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public TargetHost getTargetHost() {
        return targetHost;
    }

    public void setTargetHost(TargetHost targetHost) {
        this.targetHost = targetHost;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
