package cn.dzp.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
//链式编程
//    授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        首页所有人可以访问,功能页只有对应权限的人才能访问
//        请求授权的规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("level1")
                .antMatchers("/level2/**").hasRole("level2")
                .antMatchers("/level3/**").hasRole("level3");
//        没有权限默认会跳到登录页面,需要开启登录的页面
        //会转发到login请求,并非是我们写的,而是自带的
//        自己定义一个login页面,不使用默认的
        http.formLogin().loginPage("/toLogin").usernameParameter("user").passwordParameter("pwd").loginProcessingUrl("/login");
//        防止网站攻击:get;post
        http.csrf().disable();//关闭csrf(跨站请求伪造)功能,登出失败可能产生的原因
//        开启注销功能
        http.logout().logoutSuccessUrl("/");
//        开启记住我功能
        http.rememberMe().rememberMeParameter("remember");
    }
    //    认证,springboot 2.1.x可以直接使用,其他版本会报错
    //    密码编码:PasswordEncoder
//    在spring security 5.0+新增了很多的加密方法
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        这些数据应该从数据库里读取,使用jdbcAuthentication()
//        目前方式是在内存中读取
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("level1")
                .and()
                .withUser("dzp").password(new BCryptPasswordEncoder().encode("456789")).roles("level1","level2")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("root")).roles("level3","level2","level1");
    }

}
