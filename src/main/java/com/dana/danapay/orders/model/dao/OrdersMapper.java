package com.dana.danapay.orders.model.dao;

import com.dana.danapay.orderMenu.model.dto.OrderMenuDTO;
import com.dana.danapay.orders.model.dto.OrdersDTO;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

@Mapper
public interface OrdersMapper {

    // ORDERS-1. 선택 메뉴 주문
    void order(OrdersDTO ordersDTO);

    // ORDERS-1. 선택 메뉴 주문 - 메뉴
//    void orderMenu(List<OrderMenuDTO> orderMenuList);
    void orderMenu(OrderMenuDTO orderMenuDTO);
}
