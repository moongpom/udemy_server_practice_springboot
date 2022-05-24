package com.example.demo.src.user.model;


import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class GetUserFeedRes {
    private boolean _isMyFeed; //나의 피드를 볼때와 다른 유저 필드볼때를 구별해주기 위함
    private GetUserInfoRes getUserInfo;
    private List<GetUserPostsRes> getUserPosts;

}
