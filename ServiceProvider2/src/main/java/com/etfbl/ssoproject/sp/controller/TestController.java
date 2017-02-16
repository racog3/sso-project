package com.etfbl.ssoproject.sp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class TestController {

    @RequestMapping("/protectedResource")
    public String protectedResource() {
        return "protected";
    }
}
