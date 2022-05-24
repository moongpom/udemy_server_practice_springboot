package com.example.demo.src.post.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
@AllArgsConstructor
public class DeletePostReq {
    private int userIdx;
    //private String content;
    DeletePostReq(){};
}