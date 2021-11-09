package com.security.jwtpractice.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter2 implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        System.out.println("=====================");
        System.out.println("필터 2 ");
        System.out.println("=====================");
        chain.doFilter(req,res);

    }
}
