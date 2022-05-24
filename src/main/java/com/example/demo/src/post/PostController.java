package com.example.demo.src.post;

import com.example.demo.config.BaseException;
import com.example.demo.config.BaseResponse;
import com.example.demo.config.BaseResponseStatus;
import com.example.demo.src.post.model.*;
import com.example.demo.src.user.model.PatchUserReq;
import com.example.demo.utils.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;


//import static com.example.demo.config.BaseResponseStatus.POST_POSTS_EMPTY_IMGURL;




import static com.example.demo.utils.ValidationRegex.*;
//import static com.example.demo.utils.ValidationRegex.isRegexNickName;


@RestController
@RequestMapping("/posts")
public class PostController {
    final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Autowired
    private final PostProvider postProvider;
    @Autowired
    private final PostService postService;
    @Autowired
    private final JwtService jwtService;




    public PostController(PostProvider postProvider, PostService postService, JwtService jwtService){
        this.postProvider = postProvider;
        this.postService = postService;
        this.jwtService = jwtService;
    }




    @ResponseBody
    @GetMapping("")
    public BaseResponse<List<GetPostsRes>> getPosts(@RequestParam int userIdx){
        try{

            List<GetPostsRes> getPostsRes=postProvider.retrievePosts(userIdx);

            return new BaseResponse<>(getPostsRes);
        } catch (BaseException exception){
            return new BaseResponse<>(exception.getStatus());
        }
    }

    @ResponseBody
    @PostMapping("")
    public BaseResponse<PostPostsRes> createPost(@RequestBody PostPostsReq postPostsReq) {

        try{//형식적 validation

            if(postPostsReq.getContent().length()>450){
                return new BaseResponse<>(BaseResponseStatus.POST_POSTS_INVALID_CONTENTS);
            }
            if(postPostsReq.getPostImgUrl().size()<1){
                return new BaseResponse<>(BaseResponseStatus.POST_POSTS_EMPTY_IMGURL);
            }
            //int userIdxByJwt = jwtService.getUserIdx();
            PostPostsRes postPostsRes = postService.createPost(postPostsReq.getUserIdx(),postPostsReq);//나중에 jwt

            return new BaseResponse<>(postPostsRes);
        } catch(BaseException exception){
            return new BaseResponse<>((exception.getStatus()));
        }
    }

    // 게시글 수정
    @ResponseBody
    @PatchMapping("/{postIdx}")
    public BaseResponse<String> modifyPost(@PathVariable("postIdx") int postIdx, @RequestBody PatchPostReq patchPostReq){
        if(patchPostReq.getContent() == null){
            return new BaseResponse<>(BaseResponseStatus.POST_POSTS_INVALID_CONTENTS);
        }
        if(patchPostReq.getContent().length()>450){
            return new BaseResponse<>(BaseResponseStatus.POST_POSTS_INVALID_CONTENTS);
        }
        try {
            //jwt에서 idx 추출.
            //int userIdxByJwt = jwtService.getUserIdx();

            postService.modifyPost(patchPostReq.getUserIdx(),postIdx,patchPostReq);
            //patchPostReq.getUserIdx() -> userIdxByJwt
            String result = "회원정보 수정을 완료하였습니다.";
            return new BaseResponse<>(result);
        } catch (BaseException exception) {
            return new BaseResponse<>((exception.getStatus()));
        }
    }

    //삭제 도전
    @ResponseBody
    @PatchMapping("/{postIdx}/status")
   // public BaseResponse<String> deletePost(@PathVariable("postIdx") int postIdx, @RequestBody DeletePostReq deletePostReq){
    public BaseResponse<String> deletePost(@PathVariable("postIdx") int postIdx){
        try {

           // postService.deletePost(deletePostReq.getUserIdx(),postIdx);
            postService.deletePost(postIdx);
            //원래 쿼리문에서는 delete안쓰긴하지만 일단 이름만 이렇게 ㅇㅇ
            //patchPostReq.getUserIdx() -> userIdxByJwt
            String result = "삭제 완료하였습니다.";
            return new BaseResponse<>(result);
        } catch (BaseException exception) {
            return new BaseResponse<>((exception.getStatus()));
        }
    }
/*
    // 게시물 삭제
    @ResponseBody
    @PatchMapping("/{postIdx}/status")
    public BaseResponse<String> deleteUser(@PathVariable("postIdx") int postIdx){
        try {

            //jwt에서 idx 추출.
            int userIdxByJwt = jwtService.getUserIdx();
            postService.deletePost(userIdxByJwt,postIdx);

            String result = "삭제되었습니다.";
            return new BaseResponse<>(result);
        } catch (BaseException exception) {
            return new BaseResponse<>((exception.getStatus()));
        }
    }*/

}