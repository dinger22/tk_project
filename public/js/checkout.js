//for courses page only

window.addEventListener( "pageshow", function ( event ) {
    
    var $input = $('#refresh');

    $input.val() == 'yes' ? location.reload(true) : $input.val('yes');
});

$.get( '/getCartItems',{}, function(data) {

    var res = JSON.parse(data);
    console.log(res);
    var html = res.html;
    $('.cart-items-container').append(html);
    $('#totalPrice2')[0].text = res.totalPrice;
    $('#charge_total').val(res.totalPrice);
    if(res.totalPrice === 0){
        $(`#product_block`).append(`
            <br />
            <h2>您目前还没有选购任何课程<h2>
        `);
        $(`#checkout_button`).remove();


    }
    //render data
});

function saveEmployee() {
    var employee_id = document.getElementById("employee").value;
    var data = { employee_id: employee_id};

    $.ajax({
        url: "/saveEmployee",
        type: "post", //send it through get method
        data: {
            employee_id: employee_id
        }
    });
}
