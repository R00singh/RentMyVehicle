import React from 'react'
import { AiOutlineStar } from "react-icons/ai";
import {FaStar, FaStarHalfAlt } from "react-icons/fa";
import styled from "styled-components"

const Wrapper = styled.div``

function Star( {star, raters} ) {


    // console.log(star); 
    // console.log(raters);
    const ratingStar =  Array.from({length:5}, (elem, index) => {
        let number = index+ 0.5;

        return <span key ={index}>
            {
                star>= index+1 ? (
                    <FaStar className='icon' />
                ) : star >= number ?(
                    <FaStarHalfAlt className='icon' />
                ) : (
                    <AiOutlineStar className='icon' />
                )
            }
        </span>
    }) 
  return (
    <Wrapper>

        <div className='icon-style'>
            {ratingStar}
            <p>({raters} customer reviews)</p>
        </div>
    </Wrapper>
  )
}

export default Star
 