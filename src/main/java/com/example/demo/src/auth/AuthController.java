package com.example.demo.src.auth;

import com.example.demo.config.BaseException;
import com.example.demo.config.BaseResponse;
import com.example.demo.src.auth.model.*;
import com.example.demo.utils.JwtService;
import java.io.UnsupportedEncodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import static com.example.demo.config.BaseResponseStatus.*;

import static com.example.demo.utils.ValidationRegex.isRegexEmail;
//import static com.example.demo.utils.ValidationRegex.isRegexPassword;


@RestController
@RequestMapping("/auth")
public class AuthController {
    final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private final AuthProvider authProvider;
    @Autowired
    private final AuthService authService;
    @Autowired
    private final JwtService jwtService;




    public AuthController(AuthProvider authProvider, AuthService authService, JwtService jwtService){
        this.authProvider = authProvider;
        this.authService = authService;
        this.jwtService = jwtService;
    }



    // 로그인
    @ResponseBody
    @PostMapping("/login")
    public BaseResponse<PostLoginRes> logIn(@RequestBody PostLoginReq postLoginReq){
        try{

            // TODO: 로그인 값들에 대한 형식적인 validatin 처리해주셔야합니다!
            // TODO: 유저의 status ex) 비활성화된 유저, 탈퇴한 유저 등을 관리해주고 있다면 해당 부분에 대한 validation 처리도 해주셔야합니다.
            if(postLoginReq.getEmail() == null){
                return new BaseResponse<>(POST_USERS_EMPTY_EMAIL);
            }
            if(postLoginReq.getPwd() == null){
                return new BaseResponse<>(POST_USERS_EMPTY_PASSWORD);
            }

            if(!isRegexEmail(postLoginReq.getEmail())){
                return new BaseResponse<>(POST_USERS_INVALID_EMAIL);
            }
            //  if(!isRegexPassword(postLoginReq.getPwd())){
            //    return new BaseResponse<>(POST_USERS_INVALID_PASSWORD);
            //}
            PostLoginRes postLoginRes = authService.login(postLoginReq);
            return new BaseResponse<>(postLoginRes);
        } catch (BaseException exception){
            return new BaseResponse<>(exception.getStatus());
        }
    }

    @ResponseBody
    @GetMapping("/autologin")
    public BaseResponse<GetAutoLoginRes> autologin() throws BaseException{
        try{
            if(jwtService.getJwt()==null){
                return new BaseResponse<>(EMPTY_JWT);
            }
            else if(jwtService.checkJwt(jwtService.getJwt())==1){
                return new BaseResponse<>(INVALID_JWT);
            }
            else{
                System.out.println("autologin 오류없이 시작");
                String jwt=jwtService.getJwt();
              //  System.out.println("1autologin - getJwt"+jwt);
                int userIdx=jwtService.getUserIdx();
               // System.out.println("2autologin - jwtService.getUserIdx()" + userIdx);
                String autoSuc = "자동로그인상태입니다";
                GetAutoLoginRes getAutoRes = new GetAutoLoginRes(userIdx,autoSuc);
               // System.out.println("3autologin - getAutoRes" + getAutoRes);
                return new BaseResponse<>(getAutoRes);
            }

        }catch(BaseException exception){
            return new BaseResponse<>((exception.getStatus()));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }

    }

}