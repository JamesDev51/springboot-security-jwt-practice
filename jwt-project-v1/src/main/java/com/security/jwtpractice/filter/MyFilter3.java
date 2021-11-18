package com.security.jwtpractice.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req= (HttpServletRequest)  request;
        HttpServletResponse res = (HttpServletResponse) response;

        /*
        토큰 : "cos" 이걸 만들어 줘야함. id,pw가 정상적으로 들어와서 로그인이 완료되고 토큰을 만들어 주고 그걸 응답을 해준다.
        요청을 할 때마다 header 에 Authorization 에 value 값으로 토큰을 가지고 옴
        그 때 토큰이 넘어 오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 하면 됨. (RSA /HS256 => 토큰 검증)
         */
        if(req.getMethod().equals("POST")){
            System.out.println("============================");
            System.out.println("필터 3: POST 요청됨 ");
            String headerAuth = req.getHeader("Authorization");
            if(headerAuth.equals("cos")){
                System.out.println("인증됨 : cos");
                chain.doFilter(req,res);
                System.out.println("==========================");
            }else{
                System.out.println("인증 안됨 : cos ");
                PrintWriter out = res.getWriter();
                out.println("인증 안됨.");
                System.out.println("===========================");
            }
        }

    }
}
