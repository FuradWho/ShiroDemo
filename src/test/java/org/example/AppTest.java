package org.example;

import static org.junit.Assert.assertTrue;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.SimpleAccountRealm;
import org.apache.shiro.subject.Subject;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit test for simple App.
 */
public class AppTest {

    SimpleAccountRealm simpleAccountRealm = new SimpleAccountRealm();

    /**
     * 添加用户
     */
    @Before
    public void addUser() {
        simpleAccountRealm.addAccount("admin", "1234567");
    }

    @Test
    public void testAuthentication() {

        /*
        流程如下：
            首先调用 Subject.login(token) 进行登录，其会自动委托给 Security Manager，调用之前必须通过 SecurityUtils.setSecurityManager() 设置；
            SecurityManager 负责真正的身份验证逻辑；它会委托给 Authenticator 进行身份验证；
            Authenticator 才是真正的身份验证者，Shiro API 中核心的身份认证入口点，此处可以自定义插入自己的实现；
            Authenticator 可能会委托给相应的 AuthenticationStrategy 进行多 Realm 身份验证，默认 ModularRealmAuthenticator 会调用 AuthenticationStrategy 进行多 Realm 身份验证；
            Authenticator 会把相应的 token 传入 Realm，从 Realm 获取身份验证信息，如果没有返回 / 抛出异常表示身份验证失败了。此处可以配置多个 Realm，将按照相应的顺序及策略进行访问。
         */

        //1.构建SecurityManager
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(simpleAccountRealm);

        //2.主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        //获得当前主体
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken token = new UsernamePasswordToken("admin", "1234567");
        //登录
        subject.login(token);

        //3.subject.isAuthenticated()方法返回一个boolean值,用于判断用户是否认证成功
        Boolean flag = subject.isAuthenticated();
        System.out.println(flag);
        //登出
        subject.logout();
        flag = subject.isAuthenticated();
        System.out.println(flag);

    }


    @Test
    public void testAuthenticationByRealm() {

        // 实现自己的 Realm 实例
        MyRealm myRealm = new MyRealm();

        // 1.构建SecurityManager环境
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        defaultSecurityManager.setRealm(myRealm);

        // 2.主体提交认证请求
        SecurityUtils.setSecurityManager(defaultSecurityManager); // 设置SecurityManager环境
        Subject subject = SecurityUtils.getSubject(); // 获取当前主体

        UsernamePasswordToken token = new UsernamePasswordToken("admin", "123456789");
        subject.login(token); // 登录

        // subject.isAuthenticated()方法返回一个boolean值,用于判断用户是否认证成功
        System.out.println("isAuthenticated:" + subject.isAuthenticated()); // 输出true
            // 判断subject是否具有admin和user两个角色权限,如没有则会报错
        subject.checkRoles("admin", "user");
        //subject.checkRole("xxx"); // 报错
            // 判断subject是否具有user:add权限
        subject.checkPermission("user:add");
    }
}
