package com.mason.oauthresource.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;


@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(HttpSecurity http) throws Exception {

        //关闭csrf
        http.csrf().disable();

        // 解决跨域
        http.cors();

        // 登录，此处可以不设置，默认会跳转到SpringSecurity的登录页面
//        http.formLogin();

        // 设置认证的action
        http.authorizeRequests()
                // 不拦截以下action
                .antMatchers("/data/common")
                .permitAll()

                // 处了上面的action，都需要鉴权认证
                .anyRequest().authenticated();

    }


}
