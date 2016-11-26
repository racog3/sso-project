package com.etfbl.ssoproject.sp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Created by Rajo on 19.4.2016..
 */
@Controller
public class GreetingController {

    @RequestMapping("/greeting")
    public String greeting() {
        return "hello";
    }
}
