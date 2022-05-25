package com.example.demo.utils;


import com.example.demo.config.BaseException;
import com.example.demo.config.secret.Secret;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.io.UnsupportedEncodingException;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;

import static com.example.demo.config.BaseResponseStatus.*;

@Service
public class JwtService {

    /*
    JWT 생성
    @param userIdx
    @return String
     */
    public String createJwt(int userIdx){
        Date now = new Date();
        return Jwts.builder()
                .setHeaderParam("type","jwt")
                .claim("userIdx",userIdx)
                .setIssuedAt(now)
                .setExpiration(new Date(System.currentTimeMillis()+1*(1000*60*60*24*365)))
                .signWith(SignatureAlgorithm.HS256, Secret.JWT_SECRET_KEY)
                .compact();
    }

    /*
    Header에서 X-ACCESS-TOKEN 으로 JWT 추출
    @return String
     */
    public String getJwt(){
        HttpServletRequest request = ((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getRequest();
        return request.getHeader("X-ACCESS-TOKEN");
    }

    /*
    JWT에서 userIdx 추출
    @return int
    @throws BaseException
     */
    public int getUserIdx() throws BaseException{
        //1. JWT 추출
        String accessToken = getJwt();
        if(accessToken == null || accessToken.length() == 0){
            throw new BaseException(EMPTY_JWT);
        }

        // 2. JWT parsing
        Jws<Claims> claims;
        try{
            claims = Jwts.parser()
                    .setSigningKey(Secret.JWT_SECRET_KEY)
                    .parseClaimsJws(accessToken);
        } catch (Exception ignored) {
            throw new BaseException(INVALID_JWT);
        }

        // 3. userIdx 추출
        return claims.getBody().get("userIdx",Integer.class);
    }


    public int checkJwt(String jwt) throws UnsupportedEncodingException {
        int claimMap = 1;
        try {
            System.out.println("JWTSERVICE에서checkJwt시작");
          // 암호화 키로 복호화한다.
                // 즉 암호화 키가 다르면 에러가 발생한다.
            System.out.println("JWTSERVICE에서 파싱확인"+Jwts.parser().setSigningKey(Secret.JWT_SECRET_KEY).parseClaimsJws(jwt));



            Claims claims = Jwts.parser()
                .setSigningKey(Secret.JWT_SECRET_KEY) // 키 설정
                .parseClaimsJws(jwt) // jwt의 정보를 파싱해서 시그니처 값을 검증한다.
                .getBody();
            System.out.println("JWTSERVICE에서 claims확인"+claims);
           // if (claims )
            {claimMap = 0;}

        } catch (ExpiredJwtException e) { // 토큰이 만료되었을 경우
            System.out.println(e);

        } catch (Exception e) { // 나머지 에러의 경우
            System.out.println(e);
        }
        return claimMap;
    }

}
