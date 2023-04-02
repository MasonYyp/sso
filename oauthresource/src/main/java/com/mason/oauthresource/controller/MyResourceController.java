package com.mason.oauthresource.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
@RequestMapping("/data")
public class MyResourceController {

    @PostMapping("/common")
    public String common(){
        return "My common data";
    }

    @PostMapping("/info")
    public String info(){
        return "Data -- I am Mason";
    }
}
