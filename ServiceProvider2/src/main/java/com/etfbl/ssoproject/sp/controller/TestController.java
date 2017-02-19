package com.etfbl.ssoproject.sp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class TestController {

    @RequestMapping(value = "/")
    public String index() {
        return "index";
    }

    @RequestMapping("/protectedResource")
    public String protectedResource() {
        return "protected";
    }

    @RequestMapping("/protectedResource2")
    public String protectedResource2() {
        return "protected";
    }
}
