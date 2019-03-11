//for courses page only
$.get( '/getCourses/all',{}, function(data) {
    $('.row.g-pt-30.g-mb-50').html(data);
    //render data
});

function getFilteredCourses(event) {
    var category = event.target.id;
    $('#theButton')[0].textContent = event.target.text;
    $.get( '/getCourses/'+category,{}, function(data) {
        $('.row.g-pt-30.g-mb-50').html(data);
    });
}

window.addEventListener( "pageshow", function ( event ) {
    debugger;
    var $input = $('#refresh');

    $input.val() == 'yes' ? location.reload(true) : $input.val('yes');
});


// $.get( '/getCartItems',{}, function(data) {
//     var 
//     for(var i = 0; i < da)
//     $(".mini-cart").append(                
//         `
//         <div class="u-basket__product g-brd-none g-px-20">
//             <div class="row no-gutters g-pb-5">

//             <div class="col-8">
//                 <h6 class="g-font-weight-400 g-font-size-default">
//                 <a class="g-color-black g-color-primary--hover g-text-underline--none--hover">`+res.title+`</a>
//                 </h6>
//                 <small class="g-color-primary g-font-size-12">1 x CAD$`+res.regular_price+`</small>
//             </div>
//             </div>

//         </div>
//         `);
//     //render data
// });

