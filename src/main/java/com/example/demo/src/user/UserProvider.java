package com.example.demo.src.user;


import com.example.demo.config.BaseException;
import com.example.demo.src.user.model.GetUserFeedRes;
import com.example.demo.src.user.model.GetUserInfoRes;
import com.example.demo.src.user.model.GetUserPostsRes;
import com.example.demo.src.user.model.GetUserRes;
import com.example.demo.utils.JwtService;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import static com.example.demo.config.BaseResponseStatus.DATABASE_ERROR;
import static com.example.demo.config.BaseResponseStatus.USERS_EMPTY_USER_ID;


//Provider : Read의 비즈니스 로직 처리
@Service
public class UserProvider {

    private final UserDao userDao;
    private final JwtService jwtService;


    final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    public UserProvider(UserDao userDao, JwtService jwtService) {
        this.userDao = userDao;
        this.jwtService = jwtService;
    }


    public GetUserFeedRes retrieveUserFeed(int userIdxJwt,int userIdx) throws BaseException{
        //userIdxJwt 은 로그인해서 받아온 값이고 userIdx는 path로 받아온것
        //8주차에선 우선 controller jwt값부분을 userIdx로 보내둠
        Boolean isMyFeed=true;
        if(checkUserExist(userIdx) ==0){
            throw new BaseException(USERS_EMPTY_USER_ID);
        }
        try{
            if(userIdxJwt!=userIdx)//이둘이 같으면 내 피드
                isMyFeed=false;
            GetUserInfoRes getUserInfo = userDao.selectUserInfo(userIdx);
            List<GetUserPostsRes> getUserPosts = userDao.selectUserPosts(userIdx);
            GetUserFeedRes getUsersRes =new GetUserFeedRes(isMyFeed,getUserInfo,getUserPosts);
            return getUsersRes;
        }
        catch (Exception exception) {
            throw new BaseException(DATABASE_ERROR);
        }
                    }


    public GetUserRes getUsersByIdx(int userIdx) throws BaseException{
        try{
            GetUserRes getUsersRes = userDao.getUsersByIdx(userIdx);
            return getUsersRes;
        }
        catch (Exception exception) {
            throw new BaseException(DATABASE_ERROR);
        }
    }


    public int checkEmail(String email) throws BaseException{
        try{
            return userDao.checkEmail(email);
        } catch (Exception exception){
            throw new BaseException(DATABASE_ERROR);
        }
    }

    // 유저 확인
    public int checkUserExist(int userIdx) throws BaseException{
        try{
            return userDao.checkUserExist(userIdx);
        } catch (Exception exception){
            throw new BaseException(DATABASE_ERROR);
        }
    }

    public int deleteUser(int userIdx) throws BaseException{
        if(checkUserExist(userIdx) ==0){
            logger.error("유저없음!!|nㅇㅇ");
            throw new BaseException(USERS_EMPTY_USER_ID);
        }
        else
        {
            logger.error("else들어오나?\n");
            try{
                System.out.println("\n아니 이게 지금 왜가냐오\n");
                int deleteUser =userDao.deleteUser(userIdx);
                return deleteUser;
            }
            catch (Exception exception){
            logger.error("DeleteUserProvider",exception);
                throw new BaseException(DATABASE_ERROR);
            }
        }
    }

}
